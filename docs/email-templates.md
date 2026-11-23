# Customer email templates

## 1. Meeting request
**Subject:** APIM security advisory (MZK9-GH0) – quick call

Hi <name>,

Following up on the Azure API Management security advisory (MZK9-GH0). These subscriptions are listed as impacted: <subs>.

Microsoft closed the access path on 19 Nov, but secrets stored in APIM before that date may have been exposed. The recommended action is to rotate them.

Can we meet <day> to go through it and agree a remediation plan (45 min)?
1. Recap of the advisory
2. Review the Named values on each instance and which backends they unlock
3. Agree rotation order, owners and dates
4. List the client apps that use APIM subscription keys before we regenerate them
5. Next steps: Key Vault references, managed identity, log review

Please bring someone with access to the APIM instances, and a list of the client apps that call APIM.

Thanks,
<you>

## 2. Recap after the call
**Subject:** APIM advisory – recap and next steps

Hi <name>,

Thanks for the call. Recap:

**<instance A>** ✅ <what was done>

**<instance B>, <instance C>**
1. Check which client apps use which APIM subscription key
2. Rotate the APIM subscription keys (secondary → switch → primary), including the built-in all-access key
3. Rotate the backend keys at the source (<LLM provider / GPT / app secrets>), then update the Named values
4. Move these keys to Key Vault and reference them from APIM
5. Delete the default Starter/Unlimited products if they're unused

Tracker attached. Let me know when each step is done.

Thanks,
<you>
