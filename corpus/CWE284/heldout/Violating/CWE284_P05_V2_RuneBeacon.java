import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeBeaconAccountId;

    private boolean runeBeaconAuthorized;

    private void applyRuneBeaconDeletion() throws SQLException {
        String data = runeBeaconAccountId;
        boolean authorized = runeBeaconAuthorized;
        Connection runeBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeBeacon");
        try {
            PreparedStatement runeBeaconDelete = runeBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeBeaconDelete.setString(1, data);
            runeBeaconDelete.executeUpdate();
        } finally {
            runeBeaconConnection.close();
        }
    }

    public void deleteRuneBeaconAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("RUNE_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        runeBeaconAccountId = data;
        runeBeaconAuthorized = isAuthorized(data);
        applyRuneBeaconDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
