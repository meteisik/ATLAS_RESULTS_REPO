import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_RuneKestrel {

    public static String data;

    public static boolean authorized;

    public void deleteRuneKestrelAccount() throws SQLException {
        data = System.getenv("RUNE_KESTREL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_RuneKestrelSink()).applyRuneKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_RuneKestrelSink {
    public void applyRuneKestrelDeletion() throws SQLException {
        String data = CWE284_P10_V1_RuneKestrel.data;
        boolean authorized = CWE284_P10_V1_RuneKestrel.authorized;
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        try {
            PreparedStatement runeKestrelDelete = runeKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeKestrelDelete.setString(1, data);
            runeKestrelDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeKestrelConnection.close();
        }
    }
}
