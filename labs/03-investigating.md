# Investigating

You've seen an alert or are exploring an issue (*you're threat hunting*). You now need to be able to dive into the
event data and figure out what happened, to what extent, which systems are involved and so on.

## SSH Traffic from the Outside

### Scenario

As a security engineer, you imagine that at some point, there will be unwanted SSH connections going to systems that no
one normally connects to. You're tasked with making sure that when it happens you'll be able to find out.
In our workshop sandbox, we've simulated that event for you.

Would you be able to find the connections attempts? Can you tell which one were successful (i.e. attacker got a shell)?
Using the learnings from the previous lab, can you draft how an alert for this event would look like?

> **Tip**: Successful SSH connections result in more data being sent over the wire than unsuccessful ones.

### Breadcrumbs

- Find connections to the conventional SSH port: 22 (TCP)
- Figure out the event format
- Find a way to understand if the connection was successful (attacker got a shell) or not

> **Note**: In a real environment, SSH may be running on different ports, so you might need some protocol analysis as
> well. Additionally, in some cases you might want to use different log sources, such as SSH logs themselves, if
> available - or use them in combination with other types of logs.
