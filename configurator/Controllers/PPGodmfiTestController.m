//
//  PPGodmfiTestController.m
//
#import "PPGodmfiTestController.h"
#import "../Services/PPDaemonStatus.h"

// The verdict-matrix test script, installed by the package.
static NSString *const kTestScript = @"/opt/pluginplayground/tests/amfi-verdict-matrix.sh";

@interface PPGodmfiTestController ()
@property (strong) NSWindow *window;
@property (weak)   NSTextField *statusLabel;
@property (weak)   NSButton *runButton;
@property (weak)   NSProgressIndicator *spinner;
@property (weak)   NSTextView *textView;
@property (assign) BOOL running;
@end

@implementation PPGodmfiTestController

- (void)showWindow {
    if (!self.window) [self buildWindow];
    [self refreshStatus];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)buildWindow {
    NSRect frame = NSMakeRect(0, 0, 680, 520);
    NSWindow *win = [[NSWindow alloc] initWithContentRect:frame
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                   NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable)
        backing:NSBackingStoreBuffered defer:NO];
    win.title = @"godmfi — amfid verdict tests";
    win.releasedWhenClosed = NO;
    win.minSize = NSMakeSize(520, 360);
    [win center];
    NSView *content = win.contentView;

    // Header
    NSTextField *header = [self labelWithFrame:NSMakeRect(20, 484, 640, 22)
                                        string:@"amfid verdict matrix"];
    header.font = [NSFont boldSystemFontOfSize:15];
    header.autoresizingMask = NSViewMinYMargin | NSViewWidthSizable;
    [content addSubview:header];

    NSTextField *subtitle = [self labelWithFrame:NSMakeRect(20, 446, 640, 34)
        string:@"Rebuilds a tiny probe signed seven ways and reports which the godmfi-patched "
               @"amfid lets run. Requires administrator privileges (god-signing unlocks the root keychain)."];
    subtitle.font = [NSFont systemFontOfSize:11];
    subtitle.textColor = [NSColor secondaryLabelColor];
    subtitle.autoresizingMask = NSViewMinYMargin | NSViewWidthSizable;
    [content addSubview:subtitle];

    // Status line
    NSTextField *status = [self labelWithFrame:NSMakeRect(20, 416, 420, 18) string:@""];
    status.font = [NSFont systemFontOfSize:11];
    status.autoresizingMask = NSViewMinYMargin | NSViewWidthSizable;
    [content addSubview:status];
    self.statusLabel = status;

    // Spinner
    NSProgressIndicator *spin = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(452, 414, 18, 18)];
    spin.style = NSProgressIndicatorStyleSpinning;
    spin.displayedWhenStopped = NO;
    spin.autoresizingMask = NSViewMinXMargin | NSViewMinYMargin;
    [content addSubview:spin];
    self.spinner = spin;

    // Run button
    NSButton *run = [[NSButton alloc] initWithFrame:NSMakeRect(500, 410, 160, 28)];
    run.title = @"Run Tests";
    run.bezelStyle = NSBezelStyleRounded;
    run.keyEquivalent = @"\r";
    run.target = self;
    run.action = @selector(runTests:);
    run.autoresizingMask = NSViewMinXMargin | NSViewMinYMargin;
    [content addSubview:run];
    self.runButton = run;

    // Output text view in a scroll view
    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 20, 640, 376)];
    scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    scroll.hasVerticalScroller = YES;
    scroll.hasHorizontalScroller = YES;
    scroll.borderType = NSBezelBorder;
    scroll.autohidesScrollers = NO;

    NSTextView *tv = [[NSTextView alloc] initWithFrame:scroll.contentView.bounds];
    tv.editable = NO;
    tv.richText = NO;
    tv.drawsBackground = YES;
    tv.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
    tv.minSize = NSMakeSize(0, 0);
    tv.maxSize = NSMakeSize(FLT_MAX, FLT_MAX);
    tv.verticallyResizable = YES;
    tv.horizontallyResizable = YES;
    tv.autoresizingMask = NSViewWidthSizable;
    tv.textContainer.containerSize = NSMakeSize(FLT_MAX, FLT_MAX);
    tv.textContainer.widthTracksTextView = NO;
    scroll.documentView = tv;
    [content addSubview:scroll];
    self.textView = tv;

    self.window = win;
}

- (NSTextField *)labelWithFrame:(NSRect)f string:(NSString *)s {
    NSTextField *tf = [[NSTextField alloc] initWithFrame:f];
    tf.editable = NO; tf.bordered = NO; tf.drawsBackground = NO; tf.selectable = NO;
    tf.stringValue = s;
    tf.cell.wraps = YES;
    return tf;
}

- (void)refreshStatus {
    BOOL running = [PPDaemonStatus fangsIsRunning];
    BOOL installed = [[NSFileManager defaultManager] isExecutableFileAtPath:kTestScript];
    self.statusLabel.stringValue = [NSString stringWithFormat:@"daemon: %@      test script: %@",
        running ? @"RUNNING" : @"stopped",
        installed ? @"installed" : @"NOT INSTALLED"];
    self.runButton.enabled = installed && !self.running;
    if (!installed)
        [self setOutput:[NSString stringWithFormat:
            @"Test script not found at %@\nInstall the package first.\n", kTestScript]];
}

- (void)runTests:(id)sender {
    if (self.running) return;
    self.running = YES;
    self.runButton.enabled = NO;
    [self.spinner startAnimation:nil];
    [self setOutput:@"Running… you will be asked for your administrator password.\n\n"];

    // Run the script as root via osascript. `|| true` so a non-zero exit (any FAIL) does not make
    // `do shell script` throw and discard the captured output — the pass/fail summary is in the text.
    NSString *applescript = [NSString stringWithFormat:
        @"do shell script \"%@ 2>&1 || true\" with administrator privileges", kTestScript];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSString *result;
        @try {
            NSTask *task = [[NSTask alloc] init];
            task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/osascript"];
            task.arguments = @[@"-e", applescript];
            NSPipe *outPipe = [NSPipe pipe];
            NSPipe *errPipe = [NSPipe pipe];
            task.standardOutput = outPipe;
            task.standardError = errPipe;

            NSError *err = nil;
            if (![task launchAndReturnError:&err]) {
                result = [NSString stringWithFormat:@"Failed to launch osascript: %@",
                          err.localizedDescription];
            } else {
                NSData *outData = [[outPipe fileHandleForReading] readDataToEndOfFile];
                NSData *errData = [[errPipe fileHandleForReading] readDataToEndOfFile];
                [task waitUntilExit];
                NSString *out = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding] ?: @"";
                NSString *erro = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding] ?: @"";
                if (out.length) {
                    result = out;                      // osascript echoes the shell stdout here
                } else if ([erro containsString:@"-128"]) {
                    result = @"Cancelled — administrator authorization was denied.";
                } else {
                    result = erro.length ? erro : @"(no output)";
                }
            }
        } @catch (NSException *ex) {
            result = [NSString stringWithFormat:@"Error running tests: %@", ex.reason];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self setOutput:result];
            [self.spinner stopAnimation:nil];
            self.running = NO;
            [self refreshStatus];
        });
    });
}

- (void)setOutput:(NSString *)s {
    NSDictionary *attrs = @{
        NSFontAttributeName: [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular],
        NSForegroundColorAttributeName: [NSColor textColor],
    };
    [self.textView.textStorage setAttributedString:
        [[NSAttributedString alloc] initWithString:s attributes:attrs]];
}

@end
