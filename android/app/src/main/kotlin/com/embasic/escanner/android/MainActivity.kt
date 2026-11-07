package com.embasic.escanner.android

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/**
 * Deliberately capability-free clean-room foundation.
 * No document permissions, network, image imports, or production scan UI.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = getString(R.string.foundation_only)
        })
    }
}
