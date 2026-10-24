import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_RuneRaven {

    public static String data;

    public static boolean authorized;

    public void deleteRuneRavenAccount() throws SQLException {
        data = System.getenv("RUNE_RAVEN_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_RuneRavenSink()).applyRuneRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_RuneRavenSink {
    public void applyRuneRavenDeletion() throws SQLException {
        String data = CWE284_P10_V1_RuneRaven.data;
        boolean authorized = CWE284_P10_V1_RuneRaven.authorized;
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
