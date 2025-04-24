package com.albaraka.tsa.timestampserver

import com.albaraka.tsa.timestampserver.config.TestConfig
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import

@SpringBootTest
@Import(TestConfig::class)
class TimestampServerApplicationTests {

	@Test
	fun contextLoads() {
	}

}
