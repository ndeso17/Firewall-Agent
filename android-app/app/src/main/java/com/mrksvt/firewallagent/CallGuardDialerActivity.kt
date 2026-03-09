package com.mrksvt.firewallagent

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.Settings
import android.telecom.TelecomManager
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class CallGuardDialerActivity : AppCompatActivity() {
    private lateinit var numberText: TextView
    private lateinit var titleText: TextView
    private lateinit var phonePanel: LinearLayout
    private lateinit var contactsPanel: LinearLayout
    private lateinit var simBoardPanel: LinearLayout
    private lateinit var recentListView: ListView
    private lateinit var keypadPanel: LinearLayout
    private lateinit var keypadToggleBtn: ImageButton
    private lateinit var tabPhone: TextView
    private lateinit var tabContacts: TextView
    private lateinit var tabSimBoard: TextView
    private lateinit var contactsHintText: TextView
    private lateinit var contactsListView: ListView
    private lateinit var openSimSettingsBtn: Button
    private lateinit var searchBar: LinearLayout
    private lateinit var searchInput: EditText
    private lateinit var clearSearchBtn: ImageButton

    private val digits = StringBuilder()
    private var keypadVisible = true
    private var pendingSimSlot = 0
    private var activeTab = Tab.PHONE

    private val contactEntries = mutableListOf<ContactEntry>()
    private val filteredContacts = mutableListOf<ContactEntry>()
    private lateinit var contactsAdapter: ContactAdapter

    private val recentEntries = mutableListOf<PhoneLogEntry>()
    private val filteredRecents = mutableListOf<PhoneLogEntry>()
    private lateinit var recentAdapter: RecentAdapter

    private enum class Tab { PHONE, CONTACTS, SIM_BOARD }

    private val callPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) placeCall(pendingSimSlot)
        else Toast.makeText(this, "Izin telepon ditolak.", Toast.LENGTH_SHORT).show()
    }

    private val callLogPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) loadRecentCalls()
        else Toast.makeText(this, "Izin READ_CALL_LOG ditolak.", Toast.LENGTH_SHORT).show()
    }

    private val contactsPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) loadContacts()
        else contactsHintText.text = "Izin READ_CONTACTS ditolak."
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_call_guard_dialer)

        titleText = findViewById(R.id.screenTitleText)
        phonePanel = findViewById(R.id.phoneTabPanel)
        contactsPanel = findViewById(R.id.contactsTabPanel)
        simBoardPanel = findViewById(R.id.simBoardTabPanel)
        recentListView = findViewById(R.id.recentListView)
        keypadPanel = findViewById(R.id.keypadPanel)
        keypadToggleBtn = findViewById(R.id.keypadToggleBtn)
        tabPhone = findViewById(R.id.tabPhone)
        tabContacts = findViewById(R.id.tabContacts)
        tabSimBoard = findViewById(R.id.tabSimBoard)
        contactsHintText = findViewById(R.id.contactsHintText)
        contactsListView = findViewById(R.id.contactsListView)
        openSimSettingsBtn = findViewById(R.id.openSimSettingsBtn)
        numberText = findViewById(R.id.dialNumberText)
        searchBar = findViewById(R.id.searchBar)
        searchInput = findViewById(R.id.searchInput)
        clearSearchBtn = findViewById(R.id.clearSearchBtn)

        val initial = intent?.getStringExtra("dialer_tel")?.removePrefix("tel:")?.trim().orEmpty()
        if (initial.isNotBlank()) {
            digits.clear()
            digits.append(initial)
            numberText.text = digits.toString()
        }

        findViewById<ImageButton>(R.id.topFilterBtn).setOnClickListener {
            if (activeTab == Tab.PHONE) toggleKeypad()
        }
        findViewById<ImageButton>(R.id.topSearchBtn).setOnClickListener { toggleSearch() }
        findViewById<ImageButton>(R.id.topSettingsBtn).setOnClickListener {
            startActivity(Intent(this, CallGuardActivity::class.java))
        }

        wireDigit(R.id.key1, "1")
        wireDigit(R.id.key2, "2")
        wireDigit(R.id.key3, "3")
        wireDigit(R.id.key4, "4")
        wireDigit(R.id.key5, "5")
        wireDigit(R.id.key6, "6")
        wireDigit(R.id.key7, "7")
        wireDigit(R.id.key8, "8")
        wireDigit(R.id.key9, "9")
        wireDigit(R.id.keyStar, "*")
        wireDigit(R.id.key0, "0")
        wireDigit(R.id.keyHash, "#")

        findViewById<ImageButton>(R.id.callBtnSim1).setOnClickListener { onCallPressed(0) }
        findViewById<ImageButton>(R.id.callBtnSim2).setOnClickListener { onCallPressed(1) }
        keypadToggleBtn.setOnClickListener { toggleKeypad() }

        tabPhone.setOnClickListener { activateTab(Tab.PHONE) }
        tabContacts.setOnClickListener { activateTab(Tab.CONTACTS) }
        tabSimBoard.setOnClickListener { activateTab(Tab.SIM_BOARD) }

        recentAdapter = RecentAdapter()
        recentListView.adapter = recentAdapter
        recentListView.setOnItemClickListener { _, _, pos, _ ->
            val item = filteredRecents.getOrNull(pos) ?: return@setOnItemClickListener
            digits.clear()
            digits.append(normalizeDialInput(item.number))
            numberText.text = digits.toString()
        }

        contactsAdapter = ContactAdapter()
        contactsListView.adapter = contactsAdapter
        contactsListView.setOnItemClickListener { _, _, pos, _ ->
            val c = filteredContacts.getOrNull(pos) ?: return@setOnItemClickListener
            digits.clear()
            digits.append(normalizeDialInput(c.number))
            numberText.text = digits.toString()
            activateTab(Tab.PHONE)
        }

        openSimSettingsBtn.setOnClickListener { openSimSettings() }
        clearSearchBtn.setOnClickListener {
            searchInput.setText("")
            applySearch("")
        }
        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) { applySearch(s?.toString().orEmpty()) }
        })

        activateTab(Tab.PHONE)
    }

    private fun wireDigit(id: Int, value: String) {
        findViewById<TextView>(id).setOnClickListener {
            digits.append(value)
            numberText.text = digits.toString()
        }
    }

    private fun onCallPressed(simSlot: Int) {
        pendingSimSlot = simSlot
        val out = numberText.text?.toString().orEmpty().trim()
        if (out.isEmpty()) return
        val hasCallPerm =
            ContextCompat.checkSelfPermission(this, Manifest.permission.CALL_PHONE) == PackageManager.PERMISSION_GRANTED
        if (hasCallPerm) placeCall(simSlot)
        else callPermLauncher.launch(Manifest.permission.CALL_PHONE)
    }

    private fun placeCall(simSlot: Int) {
        val out = numberText.text?.toString().orEmpty().trim()
        if (out.isEmpty()) return
        val telUri = Uri.parse("tel:$out")

        runCatching {
            val telecom = getSystemService(TelecomManager::class.java)
            if (telecom != null && telecom.defaultDialerPackage == packageName) {
                val extras = Bundle()
                telecom.callCapablePhoneAccounts.getOrNull(simSlot)?.let {
                    extras.putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, it)
                }
                telecom.placeCall(telUri, extras)
                return
            }
        }

        runCatching {
            startActivity(Intent(Intent.ACTION_CALL, telUri).apply {
                putExtra("com.android.phone.extra.slot", simSlot)
                putExtra("slot", simSlot)
                putExtra("simSlot", simSlot)
                putExtra("phone", simSlot + 1)
            })
            return
        }

        runCatching { startActivity(Intent(Intent.ACTION_DIAL, telUri)) }
            .onFailure { Toast.makeText(this, "Gagal memulai panggilan.", Toast.LENGTH_SHORT).show() }
    }

    private fun activateTab(tab: Tab) {
        activeTab = tab
        val isPhone = tab == Tab.PHONE
        val isContacts = tab == Tab.CONTACTS
        val isSim = tab == Tab.SIM_BOARD

        phonePanel.visibility = if (isPhone) View.VISIBLE else View.GONE
        contactsPanel.visibility = if (isContacts) View.VISIBLE else View.GONE
        simBoardPanel.visibility = if (isSim) View.VISIBLE else View.GONE

        titleText.text = when (tab) {
            Tab.PHONE -> "Terakhir"
            Tab.CONTACTS -> "Kontak"
            Tab.SIM_BOARD -> "Papan SIM"
        }

        setTabState(tabPhone, isPhone)
        setTabState(tabContacts, isContacts)
        setTabState(tabSimBoard, isSim)

        when (tab) {
            Tab.PHONE -> ensureCallLogPermissionAndLoad()
            Tab.CONTACTS -> ensureContactsPermissionAndLoad()
            Tab.SIM_BOARD -> Unit
        }
        applySearch(searchInput.text?.toString().orEmpty())
    }

    private fun setTabState(view: TextView, active: Boolean) {
        view.setTextColor(Color.parseColor(if (active) "#10D070" else "#A1A1AA"))
        view.setTypeface(null, if (active) Typeface.BOLD else Typeface.NORMAL)
    }

    private fun toggleKeypad() {
        keypadVisible = !keypadVisible
        keypadPanel.visibility = if (keypadVisible) View.VISIBLE else View.GONE
        keypadToggleBtn.setImageResource(
            if (keypadVisible) android.R.drawable.ic_menu_close_clear_cancel else android.R.drawable.ic_dialog_dialer,
        )
    }

    private fun toggleSearch() {
        val show = searchBar.visibility != View.VISIBLE
        searchBar.visibility = if (show) View.VISIBLE else View.GONE
        if (!show) {
            searchInput.setText("")
            applySearch("")
        }
    }

    private fun ensureCallLogPermissionAndLoad() {
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED
        if (granted) loadRecentCalls() else callLogPermLauncher.launch(Manifest.permission.READ_CALL_LOG)
    }

    private fun loadRecentCalls() {
        val cursor = contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            arrayOf(
                CallLog.Calls.NUMBER,
                CallLog.Calls.TYPE,
                CallLog.Calls.DATE,
                CallLog.Calls.DURATION,
                CallLog.Calls.CACHED_NAME,
            ),
            null,
            null,
            "${CallLog.Calls.DATE} DESC",
        )
        val rows = mutableListOf<PhoneLogEntry>()
        cursor?.use { c ->
            val nIdx = c.getColumnIndex(CallLog.Calls.NUMBER)
            val tIdx = c.getColumnIndex(CallLog.Calls.TYPE)
            val dIdx = c.getColumnIndex(CallLog.Calls.DATE)
            val duIdx = c.getColumnIndex(CallLog.Calls.DURATION)
            val nameIdx = c.getColumnIndex(CallLog.Calls.CACHED_NAME)
            while (c.moveToNext() && rows.size < 200) {
                rows += PhoneLogEntry(
                    ts = if (dIdx >= 0) c.getLong(dIdx) else 0L,
                    type = if (tIdx >= 0) c.getInt(tIdx) else -1,
                    number = if (nIdx >= 0) c.getString(nIdx).orEmpty().ifBlank { "unknown" } else "unknown",
                    durationSec = if (duIdx >= 0) c.getLong(duIdx) else 0L,
                    name = if (nameIdx >= 0) c.getString(nameIdx).orEmpty() else "",
                )
            }
        }
        recentEntries.clear()
        recentEntries.addAll(rows)
        applySearch(searchInput.text?.toString().orEmpty())
    }

    private fun ensureContactsPermissionAndLoad() {
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED
        if (granted) loadContacts() else contactsPermLauncher.launch(Manifest.permission.READ_CONTACTS)
    }

    private fun loadContacts() {
        val rows = mutableListOf<ContactEntry>()
        val cursor = contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Phone.NUMBER,
            ),
            null,
            null,
            "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} ASC",
        )
        cursor?.use { c ->
            val nIdx = c.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
            val pIdx = c.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            while (c.moveToNext() && rows.size < 500) {
                val name = if (nIdx >= 0) c.getString(nIdx).orEmpty().ifBlank { "Tanpa Nama" } else "Tanpa Nama"
                val number = if (pIdx >= 0) c.getString(pIdx).orEmpty() else ""
                if (number.isNotBlank()) rows += ContactEntry(name, number)
            }
        }
        contactEntries.clear()
        contactEntries.addAll(rows)
        applySearch(searchInput.text?.toString().orEmpty())
    }

    private fun applySearch(queryRaw: String) {
        val q = queryRaw.trim().lowercase(Locale.getDefault())

        val rec = if (q.isBlank()) recentEntries else recentEntries.filter {
            it.name.lowercase(Locale.getDefault()).contains(q) || it.number.lowercase(Locale.getDefault()).contains(q)
        }
        filteredRecents.clear()
        filteredRecents.addAll(rec)
        recentAdapter.notifyDataSetChanged()

        val con = if (q.isBlank()) contactEntries else contactEntries.filter {
            it.name.lowercase(Locale.getDefault()).contains(q) || it.number.lowercase(Locale.getDefault()).contains(q)
        }
        filteredContacts.clear()
        filteredContacts.addAll(con)
        contactsAdapter.notifyDataSetChanged()
        contactsHintText.text = if (filteredContacts.isEmpty()) "Kontak tidak ditemukan." else "${filteredContacts.size} kontak"
    }

    private fun openSimSettings() {
        val intents = listOf(
            Intent(Settings.ACTION_NETWORK_OPERATOR_SETTINGS),
            Intent("android.settings.SIM_CARD_SETTINGS"),
            Intent(Settings.ACTION_WIRELESS_SETTINGS),
        )
        intents.forEach {
            runCatching {
                startActivity(it)
                return
            }
        }
        Toast.makeText(this, "Pengaturan SIM tidak tersedia di perangkat ini.", Toast.LENGTH_SHORT).show()
    }

    private fun typeLabel(type: Int): String = when (type) {
        CallLog.Calls.INCOMING_TYPE -> "IN"
        CallLog.Calls.OUTGOING_TYPE -> "OUT"
        CallLog.Calls.MISSED_TYPE -> "MISSED"
        CallLog.Calls.REJECTED_TYPE -> "REJECTED"
        CallLog.Calls.BLOCKED_TYPE -> "BLOCKED"
        else -> "OTHER"
    }

    private fun normalizeDialInput(raw: String): String = raw.filter { it.isDigit() || it == '+' || it == '*' || it == '#' }

    private inner class ContactAdapter : BaseAdapter() {
        override fun getCount(): Int = filteredContacts.size
        override fun getItem(position: Int): Any = filteredContacts[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val row = convertView ?: LayoutInflater.from(this@CallGuardDialerActivity)
                .inflate(R.layout.item_callguard_contact, parent, false)
            val item = filteredContacts[position]
            row.findViewById<TextView>(R.id.contactAvatarText).text = item.name.firstOrNull()?.uppercase() ?: "#"
            row.findViewById<TextView>(R.id.contactNameText).text = item.name
            row.findViewById<TextView>(R.id.contactNumberText).text = item.number
            return row
        }
    }

    private inner class RecentAdapter : BaseAdapter() {
        override fun getCount(): Int = filteredRecents.size
        override fun getItem(position: Int): Any = filteredRecents[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val row = convertView ?: LayoutInflater.from(this@CallGuardDialerActivity)
                .inflate(R.layout.item_callguard_recent, parent, false)
            val item = filteredRecents[position]
            val avatar = row.findViewById<TextView>(R.id.recentAvatarText)
            val main = row.findViewById<TextView>(R.id.recentMainText)
            val meta = row.findViewById<TextView>(R.id.recentMetaText)
            val time = row.findViewById<TextView>(R.id.recentTimeText)

            val displayName = item.name.ifBlank { item.number }
            main.text = displayName
            main.setTextColor(if (item.type == CallLog.Calls.OUTGOING_TYPE) Color.parseColor("#E5E7EB") else Color.parseColor("#F87171"))
            meta.text = "${arrowForType(item.type)}  ${regionFor(item.number)}"
            time.text = relativeTime(item.ts)
            avatar.text = displayName.firstOrNull()?.uppercase() ?: "#"
            return row
        }
    }

    private fun arrowForType(type: Int): String = when (type) {
        CallLog.Calls.OUTGOING_TYPE -> "↗"
        CallLog.Calls.INCOMING_TYPE -> "↙"
        CallLog.Calls.MISSED_TYPE -> "↙"
        CallLog.Calls.BLOCKED_TYPE -> "⛔"
        else -> "•"
    }

    private fun regionFor(number: String): String {
        val n = number.replace(" ", "")
        return if (n.startsWith("+62") || n.startsWith("08")) "Indonesia" else "-"
    }

    private fun relativeTime(ts: Long): String {
        if (ts <= 0L) return "-"
        val diff = (System.currentTimeMillis() - ts).coerceAtLeast(0L)
        val h = diff / 3600000L
        if (h > 0) return "$h h lalu"
        val m = diff / 60000L
        if (m > 0) return "$m m lalu"
        return "baru saja"
    }
}

private data class ContactEntry(val name: String, val number: String)

private data class PhoneLogEntry(
    val ts: Long,
    val type: Int,
    val number: String,
    val durationSec: Long,
    val name: String,
)
