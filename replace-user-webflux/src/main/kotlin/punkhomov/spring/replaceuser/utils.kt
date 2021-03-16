package punkhomov.spring.replaceuser

import reactor.core.publisher.Mono

inline fun <T> emptyMono(): Mono<T> = Mono.empty()

inline fun <T> monoOf(data: T): Mono<T> = Mono.just(data)

inline fun <T> nullableMonoOf(data: T?): Mono<T> = Mono.justOrEmpty(data)