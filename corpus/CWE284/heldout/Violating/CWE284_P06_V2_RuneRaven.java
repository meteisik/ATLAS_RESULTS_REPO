import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneRaven {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteRuneRavenAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneRavenSink()).applyRuneRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneRavenSink {
    public void applyRuneRavenDeletion(String data, boolean authorized) throws SQLException {
        Connection runeRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeRaven");
        try {
            PreparedStatement runeRavenDelete = runeRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeRavenDelete.setString(1, data);
            runeRavenDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeRavenConnection.close();
        }
    }
}
