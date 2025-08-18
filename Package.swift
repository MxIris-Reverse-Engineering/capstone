// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "capstone",
    products: [
        .library(
            name: "Ccapstone",
            targets: ["Ccapstone"]
        ),
        .executable(
            name: "Tests",
            targets: ["Tests"]
        ),
    ],
    targets: [
        .target(
            name: "Ccapstone",
            path: "bindings/swift/Ccapstone",
            cSettings: [
                .define("CAPSTONE_HAS_ARM64"),
                .define("CAPSTONE_HAS_ARM"),
                .define("CAPSTONE_HAS_BPF"),
                .define("CAPSTONE_HAS_EVM"),
                .define("CAPSTONE_HAS_M68K"),
                .define("CAPSTONE_HAS_M680X"),
                .define("CAPSTONE_HAS_MIPS"),
                .define("CAPSTONE_HAS_MOS65XX"),
                .define("CAPSTONE_HAS_POWERPC"),
                .define("CAPSTONE_HAS_RISCV"),
                .define("CAPSTONE_HAS_SH"),
                .define("CAPSTONE_HAS_SPARC"),
                .define("CAPSTONE_HAS_SYSZ"),
                .define("CAPSTONE_HAS_TMS320C64X"),
//                .define("CAPSTONE_HAS_TRICORE"),
                .define("CAPSTONE_HAS_WASM"),
                .define("CAPSTONE_HAS_X86"),
                .define("CAPSTONE_HAS_XCORE"),
                .define("CAPSTONE_USE_SYS_DYN_MEM"),
            ],
        ),
        .executableTarget(
            name: "Tests",
            dependencies: [
                "Ccapstone"
            ],
            path: "bindings/swift/Tests"
        )
    ]
)
