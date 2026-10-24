import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneHelixSafe {

    public void deleteRuneHelixAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("RUNE_HELIX_ACCOUNT_ID");
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneHelixSafeSink()).applyRuneHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneHelixSafeSink {
    public void applyRuneHelixDeletion(String data, boolean authorized) throws SQLException {
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
