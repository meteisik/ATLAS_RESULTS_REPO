import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_RuneHelixSafe {

    public static String data;

    public static boolean authorized;

    public void deleteRuneHelixAccount() throws SQLException {
        data = System.getenv("RUNE_HELIX_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_RuneHelixSafeSink()).applyRuneHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_RuneHelixSafeSink {
    public void applyRuneHelixDeletion() throws SQLException {
        String data = CWE284_P10_V1_RuneHelixSafe.data;
        boolean authorized = CWE284_P10_V1_RuneHelixSafe.authorized;
        Connection runeHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHelix");
        try {
            PreparedStatement runeHelixDelete = runeHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHelixDelete.setString(1, data);
            if (authorized) {
                runeHelixDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeHelixConnection.close();
        }
    }
}
