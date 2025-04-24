package com.albaraka.tsa.timestampserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class TimestampServerApplication

fun main(args: Array<String>) {
    runApplication<TimestampServerApplication>(*args)
}
