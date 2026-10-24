import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteRuneBeaconAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_BEACON_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneBeaconSafeSink()).applyRuneBeaconDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneBeaconSafeSink {
    public void applyRuneBeaconDeletion(String data, boolean authorized) throws SQLException {
        Connection runeBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeBeacon");
        try {
            PreparedStatement runeBeaconDelete = runeBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeBeaconDelete.setString(1, data);
            if (authorized) {
                runeBeaconDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeBeaconConnection.close();
        }
    }
}
