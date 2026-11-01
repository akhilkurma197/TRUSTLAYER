export function hasVerifiedChromiumSandbox(result) {
  const verification = result?.isolationReport?.chromiumSandboxVerification;
  return result?.isolationReport?.chromiumSandboxEnabled === true &&
    verification?.status === 'VERIFIED' && verification?.browserSandboxEnabled === true;
}
