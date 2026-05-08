# DC0008 - WMI Creation

## Description

Initial construction of a WMI object, such as a filter, consumer, subscription, binding, or providers.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:WMI` | Creation or modification of __EventFilter, __FilterToConsumerBinding, or CommandLineEventConsumer |
| `WinEventLog:WMI` | EventCode=5857, 5858, 5860, 5861 |
| `WinEventLog:Application` | WMI Object Creation Events |
