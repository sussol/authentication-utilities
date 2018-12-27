import sha256 from 'sha256';
import Base64 from 'base-64';
import validUrl from 'valid-url';

export const AUTH_ERROR_CODES = {
  CONNECTION_FAILURE: 'Unable to connect',
  INVALID_URL: 'Invalid URL',
  INVALID_PASSWORD: 'Invalid username or password',
  MISSING_CREDENTIALS: 'Missing username and/or password',
};

const {
  CONNECTION_FAILURE,
  INVALID_URL,
  MISSING_CREDENTIALS,
} = AUTH_ERROR_CODES;

/**
* Check whether the username and password are valid given an authentication URL.
* @param  {string}   authURL   The URL to authenticate against
* @param  {string}   username  The username to test
* @param  {string}   password  The password to test
* @param  {string}   machineUUID The machine UUID to check - optional
* @return {object}             JSON formatted response object
*/
export async function authenticateAsync(authURL, username, password, machineUUID = '') {
  if (!validUrl.isWebUri(authURL)) throw new Error(INVALID_URL);
  if (username.length === 0 || password.length === 0) { // Missing username or password
    throw new Error(MISSING_CREDENTIALS);
  }

  let responseJson;
  try {
    const response = await fetch(authURL, {
      headers: {
        Authorization: getAuthHeader(username, password),
        'msupply-site-uuid': machineUUID,
      },
    });
    responseJson = await response.json();
  } catch (error) {
    throw new Error(CONNECTION_FAILURE);
  }

  if (responseJson.error) { // Most often username/password invalid, but pass up server error
    throw new Error(responseJson.error);
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
