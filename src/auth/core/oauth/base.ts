import { env } from "@/data/env/server";
import { Cookies } from "../session";

export class OAuthClient<T> {
  private get redirectUrl() {
    // Ensure trailing slash in OAUTH_REDIRECT_URL_BASE
    return new URL("github", env.OAUTH_REDIRECT_URL_BASE);
  }

  createAuthUrl(cookies: Pick<Cookies, "set">) {
    const url = new URL("https://github.com/login/oauth/authorize");
    url.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    url.searchParams.set("redirect_uri", this.redirectUrl.toString());
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "read:user user:email");

    return url.toString();
	}
	
	
}
