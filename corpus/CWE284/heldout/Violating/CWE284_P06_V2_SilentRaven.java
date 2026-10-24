import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SilentRaven {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteSilentRavenAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SilentRavenSink()).applySilentRavenDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SilentRavenSink {
    public void applySilentRavenDeletion(String data, boolean authorized) throws SQLException {
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
