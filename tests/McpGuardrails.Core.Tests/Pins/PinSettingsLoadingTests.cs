using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Pins;

/// <summary>The YAML surface of <c>scanners.pins</c>.</summary>
public sealed class PinSettingsLoadingTests
{
    [Fact]
    public void NoSection_MeansWarnOnChanges_AndWarnOnNewTools()
    {
        var pins = PolicyDocument.Empty.EffectiveScanners.EffectivePins;

        Assert.Equal(PinMode.Warn, pins.EffectiveMode);
        Assert.Equal(NewToolAction.Warn, pins.EffectiveOnNewTool);
        Assert.Null(pins.File);
        Assert.False(pins.IsOff);
    }

    [Fact]
    public void EverySetting_Loads()
    {
        var pins = PolicyLoader.Parse("""
            scanners:
              pins:
                mode: block
                on_new_tool: allow
                file: ~/team/pins.json
            """).EffectiveScanners.EffectivePins;

        Assert.Equal(PinMode.Block, pins.EffectiveMode);
        Assert.Equal(NewToolAction.Allow, pins.EffectiveOnNewTool);
        Assert.Equal("~/team/pins.json", pins.File);
    }

    [Fact]
    public void Off_IsOff()
    {
        Assert.True(PolicyLoader.Parse("scanners: { pins: { mode: off } }").EffectiveScanners.EffectivePins.IsOff);
        Assert.True(PinSettings.Disabled.IsOff);
    }

    [Theory]
    [InlineData("mode: maybe")]
    [InlineData("on_new_tool: sometimes")]
    public void AnUnknownWord_IsAnError(string setting)
    {
        Assert.Throws<PolicyException>(() => PolicyLoader.Parse($"scanners: {{ pins: {{ {setting} }} }}"));
    }

    [Theory]
    [InlineData("mode: 7", "scanners.pins.mode")]
    [InlineData("on_new_tool: 7", "scanners.pins.on_new_tool")]
    [InlineData("file: ''", "scanners.pins.file")]
    public void AValueThatParsesButMeansNothing_IsAnError(string setting, string key)
    {
        var ex = Assert.Throws<PolicyException>(() => PolicyLoader.Parse($"scanners: {{ pins: {{ {setting} }} }}"));

        Assert.Contains(key, ex.Message, StringComparison.Ordinal);
    }
}
