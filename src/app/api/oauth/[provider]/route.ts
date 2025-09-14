import { OAuthClient } from "@/auth/core/oauth/base";
import { createUserSession } from "@/auth/core/session";
import { db } from "@/drizzle/db";
import {
	OAuthProvider,
	oAuthProviders,
	UserOAuthAccountTable,
	UserTable,
} from "@/drizzle/schema";
import { eq } from "drizzle-orm";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { NextRequest } from "next/server";
import z from "zod";

export async function GET(
	request: NextRequest,
	{ params }: { params: Promise<{ provider: string }> }
) {
	const { provider: rawProvider } = await params;
	const code = request.nextUrl.searchParams.get("code");
	const provider = z.enum(oAuthProviders).parse(rawProvider);
	if (typeof code !== "string") {
		redirect(
			`/sign-in?oauthError=${encodeURIComponent(
				"Failed to connect. Please try again"
			)}`
		);
	}

	try {
		const oAuthUser = await new OAuthClient().fetchUser(code);
		console.log(oAuthUser);
		if (oAuthUser.email == null) {
			throw new Error("email not found");
		}
		const user = await connectUserToAccount(
			{
				id: oAuthUser.id,
				name: oAuthUser.name,
				email: oAuthUser.email as string,
			},
			provider
		);

		await createUserSession(user, await cookies());
	} catch (error) {
		console.log(error);
		redirect(
			`/sign-in?oauthError=${encodeURIComponent(
				"Failed to connect. Please try again"
			)}`
		);
	}
	redirect("/");
}

async function connectUserToAccount(
	{ id, email, name }: { id: string; name: string; email: string },
	provider: OAuthProvider
) {
	return db.transaction(async (trx) => {
		let user = await trx.query.UserTable.findFirst({
			where: eq(UserTable.email, email),
			columns: { id: true, role: true, email: true, name: true },
		});

		if (user == null) {
			const [newUser] = await trx
				.insert(UserTable)
				.values({ email, name })
				.returning({
					id: UserTable.id,
					role: UserTable.role,
					email: UserTable.email,
					name: UserTable.name,
				});
			user = newUser;
		}

		await trx
			.insert(UserOAuthAccountTable)
			.values({
				provider,
				providerAccountId: id,
				userId: user.id,
			})
			.onConflictDoNothing();

		return user; // ✅ critical
	});
}
