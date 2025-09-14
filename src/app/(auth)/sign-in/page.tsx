import { SignInForm } from "@/auth/nextjs/components/SignInForm";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default async function SignIn() {
	return (
		<div className="container mx-auto p-4 max-w-[750px]">
			<Card>
				<CardHeader>
					<CardTitle>Sign In</CardTitle>
				</CardHeader>
				<CardContent>
					<SignInForm />
				</CardContent>
			</Card>
		</div>
	);
}
