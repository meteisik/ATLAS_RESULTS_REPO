import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentRaven {

    public static String data;

    public static boolean authorized;

    public void deleteSilentRavenAccount() throws SQLException {
        data = System.getenv("SILENT_RAVEN_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentRavenSink()).applySilentRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentRavenSink {
    public void applySilentRavenDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentRaven.data;
        boolean authorized = CWE284_P10_V1_SilentRaven.authorized;
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        try {
            PreparedStatement silentRavenDelete = silentRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentRavenDelete.setString(1, data);
            silentRavenDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentRavenConnection.close();
        }
    }
}
