//Created by Salty on 8/25/26.

#import "AppDelegate.h"
#import "Controllers/PPMainViewController.h"
#import "Controllers/PPGodmfiTestController.h"
#import "Services/PPPrivledgedWriter.h"

@interface AppDelegate ()
@property (strong) PPMainViewController *mainViewController;
@property (strong) PPGodmfiTestController *godmfiController;
@property (strong) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    self.mainViewController = [[PPMainViewController alloc] initWithNibName:@"PPMainViewView"
                                                                     bundle:nil];
    
    if (!self.mainViewController)
        return;
    
    [self.mainViewController.view setFrame:self.window.contentView.bounds];
    [self.window.contentView setSubviews:@[self.mainViewController.view]];

    [PPPrivledgedWriter createMasterOptionsIfNotExists];

    [self installGodmfiMenu];
}

// Add a top-level "godmfi" menu with an item that opens the verdict-test window.
- (void)installGodmfiMenu {
    NSMenu *mainMenu = [NSApp mainMenu];
    if (!mainMenu || [mainMenu indexOfItemWithTitle:@"godmfi"] >= 0)
        return;

    NSMenuItem *top = [[NSMenuItem alloc] initWithTitle:@"godmfi" action:nil keyEquivalent:@""];
    NSMenu *sub = [[NSMenu alloc] initWithTitle:@"godmfi"];

    NSMenuItem *tests = [[NSMenuItem alloc] initWithTitle:@"Verdict Tests…"
                                                   action:@selector(showGodmfiTests:)
                                            keyEquivalent:@"t"];
    tests.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagShift;
    tests.target = self;
    [sub addItem:tests];
    top.submenu = sub;

    NSInteger idx = [mainMenu indexOfItemWithTitle:@"Window"];
    if (idx < 0) idx = mainMenu.numberOfItems;
    [mainMenu insertItem:top atIndex:idx];
}

- (void)showGodmfiTests:(id)sender {
    if (!self.godmfiController)
        self.godmfiController = [[PPGodmfiTestController alloc] init];
    [self.godmfiController showWindow];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {

}


- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app {
    return YES;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)hasVisibleWindows{
    if (!hasVisibleWindows)
        [self.window makeKeyAndOrderFront:nil];
    
    return YES;
}

@end
