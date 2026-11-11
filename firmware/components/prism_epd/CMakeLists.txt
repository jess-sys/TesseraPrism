idf_component_register(
    SRCS "prism_epd.c" "prism_epd_board.c"
    INCLUDE_DIRS "include"
    REQUIRES driver esp_timer esp_rom
)
# epdiy comes from the component registry (vroland/epdiy, declared in Cargo.toml). The managed
# component is named "vroland__epdiy" by the IDF component manager.
idf_component_get_property(_epdiy vroland__epdiy COMPONENT_LIB)
target_link_libraries(${COMPONENT_LIB} PUBLIC ${_epdiy})
