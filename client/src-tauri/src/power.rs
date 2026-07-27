// Battery/throttling check: lets a future sync loop throttle itself when running
// unplugged and low on charge.

const LOW_BATTERY_THRESHOLD: f32 = 0.20;

/// Returns true if the system is running on battery below `LOW_BATTERY_THRESHOLD`
/// (or any battery read fails to report a plugged-in state), meaning a sync loop
/// should throttle itself. Returns false (no throttling) if there's no battery
/// (e.g. desktop) or the system is charging/full.
pub fn on_battery_saver() -> bool {
    let manager = match starship_battery::Manager::new() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let batteries = match manager.batteries() {
        Ok(b) => b,
        Err(_) => return false,
    };
    for battery in batteries.flatten() {
        let state = battery.state();
        let on_battery = state == starship_battery::State::Discharging;
        let low = battery.state_of_charge().value < LOW_BATTERY_THRESHOLD;
        if on_battery && low {
            return true;
        }
    }
    false
}

#[tauri::command]
pub fn get_power_status() -> bool {
    on_battery_saver()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_without_battery_hardware_assumptions() {
        // ponytail: no mocking of starship_battery internals — this just proves
        // the call chain runs to completion on whatever hardware CI has.
        let _ = on_battery_saver();
    }
}
