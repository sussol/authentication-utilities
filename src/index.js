import sha256 from 'sha256';
import Base64 from 'base-64';
import validUrl from 'valid-url';

export const AUTH_ERROR_CODES = {
  CONNECTION_FAILURE: 'Unable to connect',
  INVALID_URL: 'Invalid URL',
  INVALID_PASSWORD: 'Invalid username or password',
  MISSING_CREDENTIALS: 'Missing username and/or password',
  PARSING_ERROR: 'Unable to parse server response',
  LICENSE_ERROR: 'The server reported a license error',
};

const { CONNECTION_FAILURE, INVALID_URL, MISSING_CREDENTIALS, PARSING_ERROR, LICENSE_ERROR } =
  AUTH_ERROR_CODES;

/**
 * Check whether the username and password are valid given an authentication URL.
 * @param  {string}   authURL   The URL to authenticate against
 * @param  {string}   username  The username to test
 * @param  {string}   password  The password to test
 * @param  {object}   extraHeaders Extra headers to add to authentication request
 * @return {object}             JSON formatted response object
 */
export async function authenticateAsync(authURL, username, password, extraHeaders = {}) {
  if (!validUrl.isWebUri(authURL)) throw new Error(INVALID_URL);
  if (username.length === 0 || password.length === 0) {
    // Missing username or password
    throw new Error(MISSING_CREDENTIALS);
  }

  let responseJson = {};
  let bodyText = '';
  try {
    const response = await fetch(authURL, {
      headers: {
        Authorization: getAuthHeader(username, password),
        ...extraHeaders,
      },
    });
    bodyText = await response.text();
    if (bodyText.includes("license number doesn't allow you to connect")) {
      responseJson.error = LICENSE_ERROR;
    }
  } catch (error) {
    throw new Error(CONNECTION_FAILURE);
  }

  if (responseJson.error) {
    // Most often username/password invalid, but pass up server error
    throw new Error(responseJson.error);
  }

  try {
    responseJson = JSON.parse(bodyText);
  } catch (error) {
    throw new Error(PARSING_ERROR);
  }

  return responseJson;
}

/**
 * Returns a Basic auth header with the given username and password in a Base64 encoded string
 * @param  {string}   username  The username to have in the header
 * @param  {string}   password  The password to have in the header
 */
export function getAuthHeader(username, password) {
  return `Basic ${Base64.encode(`${username}:${password}`)}`;
}

/**
 * Encodes a given password using sha256 and optional salt, producing a non-reversible hash
 */
export function hashPassword(password, salt = '') {
  return sha256(`${password}${salt}`);
}
