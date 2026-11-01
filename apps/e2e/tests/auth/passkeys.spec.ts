// spec: features/auth/mfa.feature
// seed: tests/seed.spec.ts
//
// Passkeys as a second factor, driven through Chromium's virtual
// authenticator (a CDP WebAuthn emulation), so no real hardware or prompt is
// involved. Other browsers have no such emulation and are skipped. Every
// scenario works on throwaway users; the instance login policy is only ever
// pointed at a throwaway role and restored afterwards.

import { expect, type Page, test } from "@playwright/test";
import {
	allowPolicy,
	authRequest,
	BASE_URL,
	cleanupGlobalRolesByPrefix,
	cleanupUsersByPrefix,
	createGlobalRole,
	createUserWithPassword,
	newRunId,
	RESTRICTED_PASSWORD,
	signIn,
} from "../helpers/e2e-api";
import { putPolicy, restorePolicy } from "../helpers/mfa";

const PREFIX = "E2E_PASSKEY_";
const ROLE_PREFIX = "E2E_PASSKEY_ROLE_";
const RUN_ID = newRunId();
let counter = 0;

function uniqueName(label: string): string {
	counter += 1;
	return `${PREFIX}${label}_${RUN_ID}_${counter}`;
}

test.beforeEach(async ({ request, browserName }) => {
	test.skip(
		browserName !== "chromium",
		"virtual authenticators are Chromium-only",
	);
	await cleanupUsersByPrefix(request, PREFIX);
	await cleanupGlobalRolesByPrefix(request, ROLE_PREFIX);
});

test.afterEach(async ({ request, browserName }) => {
	if (browserName !== "chromium") return;
	await restorePolicy(request);
	await cleanupUsersByPrefix(request, PREFIX);
	await cleanupGlobalRolesByPrefix(request, ROLE_PREFIX);
});

/** Plugs a software authenticator that approves every prompt into the page. */
async function addAuthenticator(page: Page) {
	const cdp = await page.context().newCDPSession(page);
	await cdp.send("WebAuthn.enable");
	const { authenticatorId } = await cdp.send(
		"WebAuthn.addVirtualAuthenticator",
		{
			options: {
				protocol: "ctap2",
				transport: "internal",
				hasResidentKey: true,
				hasUserVerification: true,
				isUserVerified: true,
				automaticPresenceSimulation: true,
			},
		},
	);
	return {
		credentials: async () =>
			(await cdp.send("WebAuthn.getCredentials", { authenticatorId }))
				.credentials,
	};
}

async function newUser(
	request: Parameters<typeof authRequest>[0],
	playwright: Parameters<typeof createUserWithPassword>[1],
	label: string,
	roles?: string[],
) {
	const username = uniqueName(label);
	await authRequest(request);
	await createUserWithPassword(request, playwright, {
		username,
		fullName: username,
		roles,
	});
	return username;
}

async function submitCredentials(page: Page, username: string) {
	await page.goto(`${BASE_URL}/`);
	await page.getByRole("textbox", { name: "Username" }).fill(username);
	await page
		.getByRole("textbox", { name: "Password" })
		.fill(RESTRICTED_PASSWORD);
	await page.getByRole("button", { name: "Sign in" }).click();
}

const greeting = (page: Page) =>
	page.getByRole("heading", { name: /Good (morning|afternoon|evening)/i });

test.describe("Passkeys", () => {
	test("a user adds a passkey, signs in with it, and removes it", async ({
		page,
		request,
		playwright,
	}) => {
		const username = await newUser(request, playwright, "ADD");
		const authenticator = await addAuthenticator(page);
		await signIn(page, username, RESTRICTED_PASSWORD);
		await page.goto(`${BASE_URL}/account/security`);
		await expect(page.getByRole("heading", { name: "Security" })).toBeVisible();

		await expect(
			page.getByText("You haven't added a passkey yet."),
		).toBeVisible();
		await page.getByRole("button", { name: "Add a passkey" }).click();
		const dialog = page.getByRole("dialog");
		await dialog.getByLabel("Name").fill("Work laptop");
		await dialog.getByRole("button", { name: "Continue" }).click();
		await expect(page.getByText("Work laptop")).toBeVisible();
		await expect(page.getByText("Never used")).toBeVisible();
		expect(await authenticator.credentials()).toHaveLength(1);

		// Sign out, then back in: password, then the passkey prompt.
		await page.context().clearCookies();
		await submitCredentials(page, username);
		await expect(page).toHaveURL(/\/login\/mfa/);
		await expect(
			page.getByRole("heading", { name: "Use your passkey" }),
		).toBeVisible();
		await page.getByRole("button", { name: "Use a passkey" }).click();
		await expect(greeting(page)).toBeVisible();

		// The sign-in is recorded, and removing needs the passkey again.
		await page.goto(`${BASE_URL}/account/security`);
		await expect(page.getByText(/Last used/)).toBeVisible();
		await page.getByRole("button", { name: "Remove Work laptop" }).click();
		await page
			.getByRole("dialog")
			.getByRole("button", { name: "Remove", exact: true })
			.click();
		await expect(
			page.getByText("You haven't added a passkey yet."),
		).toBeVisible();
	});

	test("a protected user sets up a passkey on the sign-in page", async ({
		page,
		request,
		playwright,
	}) => {
		const roleName = `${ROLE_PREFIX}${RUN_ID}`;
		await authRequest(request);
		await createGlobalRole(request, roleName, allowPolicy([]));
		const username = await newUser(request, playwright, "FORCED", [roleName]);
		const saved = await putPolicy(request, {
			privileged_roles: [roleName],
			require_mfa: true,
			ip_allow_list: [],
		});
		expect(saved.ok()).toBeTruthy();
		const authenticator = await addAuthenticator(page);

		await submitCredentials(page, username);
		await expect(
			page.getByRole("heading", { name: "Secure your account" }),
		).toBeVisible({ timeout: 15_000 });
		await page.getByRole("radio", { name: /Passkey/ }).check({ force: true });
		await page.getByRole("button", { name: "Continue", exact: true }).click();
		await expect(
			page.getByRole("heading", { name: "Passkey added" }),
		).toBeVisible();
		expect(await authenticator.credentials()).toHaveLength(1);
		await page.getByRole("button", { name: "Continue to sign in" }).click();

		await expect(page).toHaveURL(/\/login\/mfa/);
		await page.getByRole("button", { name: "Use a passkey" }).click();
		await expect(greeting(page)).toBeVisible();
	});

	test("a passkey from another device is refused", async ({
		page,
		request,
		playwright,
	}) => {
		const username = await newUser(request, playwright, "OTHER");
		await addAuthenticator(page);
		await signIn(page, username, RESTRICTED_PASSWORD);
		await page.goto(`${BASE_URL}/account/security`);
		await page.getByRole("button", { name: "Add a passkey" }).click();
		await page
			.getByRole("dialog")
			.getByRole("button", { name: "Continue" })
			.click();
		await expect(page.getByText("Passkey", { exact: true })).toBeVisible();

		// A fresh browser profile has an authenticator that holds no credential.
		const stranger = await page.context().browser()?.newContext();
		if (!stranger) throw new Error("no browser");
		const strangerPage = await stranger.newPage();
		await addAuthenticator(strangerPage);
		await submitCredentials(strangerPage, username);
		await strangerPage.getByRole("button", { name: "Use a passkey" }).click();
		await expect(
			strangerPage.getByText(/couldn't be verified|cancelled or timed out/),
		).toBeVisible();
		await expect(strangerPage).toHaveURL(/\/login\/mfa/);
		await stranger.close();
	});
});
