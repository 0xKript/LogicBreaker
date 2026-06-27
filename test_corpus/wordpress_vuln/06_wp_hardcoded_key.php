<?php
/**
 * Vuln WP 06: Hardcoded API key in plugin.
 */
class Weather_Plugin {

    private $api_key = 'sk-weather-live-abc123def456';

    public function get_weather($city) {
        $url = "https://api.weather.com/v1?city=" . $city . "&key=" . $this->api_key;
        return file_get_contents($url);
    }
}
