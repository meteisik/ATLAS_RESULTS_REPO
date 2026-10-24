import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneKestrelSafe {

    public void deleteRuneKestrelAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("RUNE_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneKestrelSafeSink()).applyRuneKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneKestrelSafeSink {
    public void applyRuneKestrelDeletion(String data, boolean authorized) throws SQLException {
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        try {
            PreparedStatement runeKestrelDelete = runeKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeKestrelDelete.setString(1, data);
            if (authorized) {
                runeKestrelDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeKestrelConnection.close();
        }
    }
}
