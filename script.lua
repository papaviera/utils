local inspect = require"neverlose/inspect"

local ffi = require "ffi";



pcall(ffi.cdef, [[

    typedef struct {
        float* origin;
        float* velocity;
        float* abs_velocity;
        float  simulation_time;
        float* mins;
        float  maxs_x;
        float  maxs_y;
        float  aim_yaw_max;
        int    choked_ticks;
        char   pad_44[24];
        float  desync_weight;
        char   pad_60[4];
        float  eye_pitch;
        float  abs_yaw;
        float  body_yaw;
        float* view_offset;
        float  origin_prev_x;
        float  origin_prev_y;
        int    server_tick;
        char   pad_88[12];
        float  lagcomp_simtime;
        float  duck_amount;
        char   pad_9C[4];
        float  maxs_z;
        int    lagcomp_valid;
        char   pad_A8[4];
        int    extrap_cleared;
        int    record_flags;
        char   pad_B4[4];
        void*  anim;
    } lag_record_t;

    typedef struct {
        void*          pad;
        lag_record_t** records;
        int            capacity;
        int            head;
        int            count;
    } lag_ringbuf_t;    

    typedef struct {
        void*         BaseAddress;
        void*         AllocationBase;
        unsigned long AllocationProtect;
        unsigned long RegionSize;
        unsigned long State;
        unsigned long Protect;
        unsigned long Type;
    } MEMORY_BASIC_INFORMATION;

    unsigned long VirtualQuery(const void*, MEMORY_BASIC_INFORMATION*, unsigned long);
    int   VirtualProtect(void*, unsigned long, unsigned long, unsigned long*);
    void* VirtualAlloc(void*, unsigned long, unsigned long, unsigned long);
    int   VirtualFree(void* addr, unsigned long size, unsigned long type);


]])

local memory = new_class()
    :struct "main" {
        virtual_query = function(self, address)
            local mbi = ffi.new "MEMORY_BASIC_INFORMATION";
            local result = ffi.C.VirtualQuery(address, mbi, ffi.sizeof("MEMORY_BASIC_INFORMATION"));
            
            if result ~= 0 then
                return mbi;
            end

            return nil;
        end,


        ptr = function(self, cdata)
            return tonumber(ffi.cast("uintptr_t", cdata))
        end,

        wi32 = function(self, abs_addr, v)
            local b = ffi.cast("uint8_t*", abs_addr)
            b[0] = bit.band(v, 0xFF)
            b[1] = bit.band(bit.rshift(v, 8),  0xFF)
            b[2] = bit.band(bit.rshift(v, 16), 0xFF)
            b[3] = bit.band(bit.rshift(v, 24), 0xFF)
        end,

        scan_memory = function(self, pat)
            local plen, addr = #pat, 0x10000
            while addr < 0x7FFF0000 do
                local m = self:virtual_query(ffi.cast("void*", addr))
                if not m then
                    addr = addr + 0x10000
                else
                    local base_n = tonumber(ffi.cast("uintptr_t", m.BaseAddress))
                    local end_n  = base_n + tonumber(m.RegionSize)
                    if m.State == 0x1000 and bit.band(m.Protect, 0xF0) ~= 0
                       and bit.band(m.Protect, 0x01) == 0 and bit.band(m.Protect, 0x100) == 0 then
                        local p = ffi.cast("uint8_t*", base_n)
                        for i = 0, end_n - base_n - plen do
                            local ok = true
                            for j = 1, plen do
                                if pat[j] and p[i+j-1] ~= pat[j] then ok = false; break end
                            end
                            if ok then return p + i end
                        end
                    end
                    addr = end_n > addr and end_n or (addr + 0x10000)
                end
            end
        end,

        save_memory = function(self, address, len)
            local p = ffi.cast("uint8_t*", address)
            local t = {}

            for i = 0, len - 1 do 
                t[i + 1] = p[i] 
            end

            return t
        end,

        scan_nl = function(self, base, pattern)
            local furthest_addr = 0x4158f57c;
            local closest_addr = 0x4124EAC6;

            local delta = furthest_addr - closest_addr;

            local p = ffi.cast("uint8_t*", base)

            for i = 0, delta - #pattern do
                local ok = true;

                for u = 1, #pattern do
                    if pattern[u] ~= nil and p[i + u - 1] ~= pattern[u] then
                        ok = false;
                        break;
                    end
                end

                if ok then
                    return p + i;
                end
            end
        end,

        scan_nl_all = function(self, b, pat)
            local results = {}
            local p   = ffi.cast("uint8_t*", b)
            local len = #pat

            local s = 0x4158f57c - 0x4124EAC6
            for i = 0, s - len do
                local ok = true
                for j = 1, len do
                    if pat[j] ~= nil and p[i + j - 1] ~= pat[j] then ok = false; break end
                end
                if ok then results[#results + 1] = p + i end
            end
            return results
        end,

        
        byte_patch = function(self, address, array)
            for iter, byte in ipairs(array) do
                address[iter - 1] = byte;
            end
        end,

        virtual_protect = function(self, address, size, new_protect, old_protect)
            return ffi.C.VirtualProtect(address, size, new_protect, old_protect);
        end,

        virtual_free = function(self, addr, size, type)
            return ffi.C.VirtualFree(addr, size, type);
        end,

        flush_instruction_cache = function(self, process, base, size)
            return ffi.C.FlushInstructionCache(process, base, size);
        end,

        get_current_process = function(self)
            return ffi.C.GetCurrentProcess();
        end
    }
    :struct "core" {
        results = {},

        patterns = {
            global_table = function(self, base)
                local pattern = {0x89, 0x86, 0xB0, 0x00, 0x00, 0x00, 0xA1, 0, 0, 0, 0, 0x89, 0x86, 0xAC, 0x00, 0x00, 0x00}
                local addr = self.main:scan_nl(base, pattern, false)

                if not addr then
                    return nil;
                end

                local ptr = ffi.cast("uint8_t**", ffi.cast("uint32_t*", addr + 7)[0])

                if ptr then
                    return ptr;
                end
            end,
            

            skip_valid_records = function(self, base)
                local pattern = {0xA9, 0x08, 0x08, 0x00, 0x00, 0x75, 0x0F, 0x43};
                local addr = self.main:scan_nl(base, pattern, false);

                if not addr then
                    return nil;
                end

                local ptr = addr + 6;
                return ptr;
            end,

            record_windows = function(self, base)
                local pattern = {0x83, 0xF8, 0x08, 0x0F, 0x82, nil, nil, nil, nil, 0x64, 0xA1, 0x30};
                local addresses = self.main:scan_nl_all(base, pattern);
                return addresses
            end,

            lerp_records = function(self, base)
                local pattern = {0xF3, 0x0F, 0x5E, 0xCA, 0x0F, 0x2E, 0xC8, 0x0F, 0x87, nil, nil, nil, nil, 0x66, 0xC7, 0x44, 0x32, nil, nil, nil};
                local addresses = self.main:scan_nl_all(base, pattern);

                local result = {}
                for i, addr in ipairs(addresses) do
                    if addr then
                        result[i] = addr + 7;
                    end
                end
                
                return result;
            end,
            
            extrapolation_limit = function(self, base)
                local pattern = {0xF7, 0xD9, 0x0F, 0x48, 0xC8, 0x83, 0xF9, nil, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x77};
                local addr = self.main:scan_nl(base, pattern);
                if not addr then return nil end
                local ptr = addr + 7;
                return ptr;
            end,

            freezetime_fakeduck = function(self, base)
                local pattern = {
                    0x31, 0xC0, 0x84, 0xC9,
                    0x75, nil,
                    0x80, 0x3D, nil, nil, nil, nil, 0x00,
                    0x75, nil,
                    0x8B, 0x35
                }

                local addr = self.main:scan_nl(base, pattern);
                if not addr then return nil end
                local ptr = addr + 4;
                return ptr;
            end,

            extrapolation_adjust = function(self, base)
                local pattern = {
                    0x0F, 0x9C, 0xC0,
                    0x34, 0x01,
                    0x0F, 0xB6, 0xC0,
                    0x29, 0xC6
                }

                local addr = self.main:scan_nl(base, pattern);
                if not addr then return nil end
                local ptr = addr + 3;
                return ptr;
            end,

            break_lagcomp_distance_a = function(self, base)
                local pattern = {
                    0x49, 0x21, 0xD9, 0x8B, 0x0C, 0x88,
                    0xE8, nil, nil, nil, nil,
                    0x84, 0xC0, 0x0F, 0x84
                }

                local addr = self.main:scan_nl(base, pattern);
                if not addr then return nil end
                local ptr = addr + 6;
                return ptr;
            end,

            break_lagcomp_distance_b = function(self, base)
                local pattern = {
                    0x48, 0x21, 0xD8, 0x8B, 0x0C, 0x81,
                    0xE8, nil, nil, nil, nil,
                    0x84, 0xC0, 0x74
                }

                local addr = self.main:scan_nl(base, pattern);
                if not addr then return nil end
                local ptr = addr + 6;
                return ptr;
            end,
        },

        get_base_address = function(self)
            local a = self.main:scan_memory({0xF3,0x0F,0x5B,0xCA,0x0F,0x5B,0xC9,0x0F,0x2E,0xCB})
            local region = self.main:virtual_query(a);

            if region then
                return region.AllocationBase, 0x3501000;
            end
        end,

        store_patterns = function(self)
            self.results = {}

            local base, size = self:get_base_address();

            for name, handler in pairs(self.patterns) do

                local result = handler(self, base)

                if result then
                    self.results[name] = result
                else
                    print(string.format("[-] failed to find '%s'", name))
                end
            end
        end,

        get_pattern_result = function(self, name)
            return self.results[name]
        end,
    }
    :struct "patch_system" {
        patches = { },
        initialized = false,

        init_all_patches = function(self)
            if self.initialized then return end

            self:init_patch("record_windows", 1);
            self:init_patch("lerp_records", 6)
            self:init_patch("skip_valid_records", 1)
            
            self:init_patch("extrapolation_limit", 1)
            self:init_patch("extrapolation_adjust", 7)
            self:init_patch("freezetime_fakeduck", 2)
            self:init_patch("break_lagcomp_distance_a", 5);
            self:init_patch("break_lagcomp_distance_b", 5);

            self.initialized = true
        end,

        init_patch = function(self, name, size)
            size = size or 8

            local patch = {
                name = name,
                patched = false,
                addresses = {},
                orig_bytes = {},
                size = size,
            }

            local result = self.core:get_pattern_result(name)
            if not result then 
                self.patches[name] = patch
                return patch 
            end

            if type(result) == "table" then
                for i, addr in ipairs(result) do
                    if addr then
                        table.insert(patch.addresses, addr)
                        table.insert(patch.orig_bytes, self.main:save_memory(addr, size))
                    end
                end
            else
                table.insert(patch.addresses, result)
                table.insert(patch.orig_bytes, self.main:save_memory(result, size))
            end

            self.patches[name] = patch
            return patch
        end,

        apply_patch = function(self, name, bytes, offset)
            offset = offset or 0;
            local patch = self.patches[name]
            if not patch or #patch.addresses == 0 then return false end

            for i, addr in ipairs(patch.addresses) do
                self.main:byte_patch(addr + offset, bytes)
            end

            patch.patched = true
            return true
        end,

        restore_patch = function(self, name)
            local patch = self.patches[name]
            if not patch then return false end

            for i, addr in ipairs(patch.addresses) do
                if patch.orig_bytes[i] then
                    self.main:byte_patch(addr, patch.orig_bytes[i])
                end
            end

            patch.patched = false
            return true
        end,

        restore_all = function(self)
            for name, patch in pairs(self.patches) do
                if patch.patched then
                    self:restore_patch(name)
                end
            end
        end,
    }

memory.core:store_patterns();

local logic = new_class()
    :struct "ui" {
        elements = { },
        init = function(self)

            local group = ui.create("hi!", "hi!", 1);

            self.elements.lerp_records = group:switch("Unlimit Records"):set_callback(function(e)
                local value = e:get();
                self.lerp_records:register_patch(value);
            end, true);
            self.elements.extrapolation_limit = group:slider("Extrapolation Limit", 2, 4, 2):set_callback(function(e)
                local value = e:get()
                self.extrapolation_limit:register_patch(value);
            end);

            self.elements.extrapolation_adjust = group:combo("Extrapolation Adjust", {
                "Off", "No Reduction"
            }):set_callback(function(e)
                local value = e:get()
                self.extrapolation_adjust:register_patch(value);
            end)


            self.elements.freezetime_fakeduck = group:switch("Fake Duck on Freeze Time"):set_callback(function(e)
                local value = e:get()
                self.freezetime_fakeduck:register_patch(value);
            end);

            self.elements.break_lagcomp_distance_a = group:switch("Remove Useless Lag Comp. delay"):set_callback(function(e)
                local value = e:get()
                self.break_lagcomp_distance_a:register_patch(value);
            end);


            self.elements.break_lagcomp_distance_b = group:switch("Remove Useless Lag Comp. delay #2"):set_callback(function(e)
                local value = e:get()
                self.break_lagcomp_distance_b:register_patch(value);
            end);


            --self.elements.custom_record_selection = group:switch("Custom Record Selection");
            --self.elements.custom_fallback_selection = group:switch("Custom Fallback Selection");
            
            self.elements.skip_valid_records = group:switch("Preserve Valid Records"):set_callback(function(e)
                local value = e:get()
                self.skip_valid_records:register_patch(value);
            end);

            self.elements.HAHAHAHHAHAH = group:switch("Disable Soufiw's stupidness"):disabled(true);
        end,
    }
    :struct "lerp_records" {
        register_patch = function(self, enabled)
            if enabled then
                memory.patch_system:apply_patch("lerp_records", {0x90, 0x90, 0x90, 0x90, 0x90, 0x90})
            else
                memory.patch_system:restore_patch("lerp_records")
            end
        end
    }
    :struct "extrapolation_limit" {
        register_patch = function(self, value)
            memory.patch_system:apply_patch("extrapolation_limit", {value});
        end
    }
    :struct "extrapolation_adjust" {
        register_patch = function(self, value)
            if value == "No Reduction" then
                memory.patch_system:apply_patch("extrapolation_adjust", {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90})
            else
                memory.patch_system:restore_patch("extrapolation_adjust")
            end
        end
    }
    :struct "freezetime_fakeduck" {
        register_patch = function(self, enabled)
            if enabled then
                memory.patch_system:apply_patch("freezetime_fakeduck", {0x90, 0x90})
            else
                memory.patch_system:restore_patch("freezetime_fakeduck")
            end
        end
    }
    :struct "break_lagcomp_distance_a" {
        register_patch = function(self, enabled)
            if enabled then
                memory.patch_system:apply_patch("break_lagcomp_distance_a", {0xB0, 0x00, 0x90, 0x90, 0x90})
            else
                memory.patch_system:restore_patch("break_lagcomp_distance_a")
            end
        end
    }
    :struct "break_lagcomp_distance_b" {
        register_patch = function(self, enabled)
            if enabled then
                memory.patch_system:apply_patch("break_lagcomp_distance_b", {0xB0, 0x00, 0x90, 0x90, 0x90})
            else
                memory.patch_system:restore_patch("break_lagcomp_distance_b")
            end
        end
    }
    :struct "skip_valid_records" {
        register_patch = function(self, enabled)
            if enabled then
                memory.patch_system:apply_patch("skip_valid_records", {0x00})
            else
                memory.patch_system:restore_patch("skip_valid_records")
            end
        end
    }

logic.ui:init();
memory.patch_system:init_all_patches()


events.shutdown(function()
    memory.patch_system:restore_all()
end)
