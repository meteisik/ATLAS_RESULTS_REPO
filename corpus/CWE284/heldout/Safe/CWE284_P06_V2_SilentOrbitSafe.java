import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SilentOrbitSafe {
    private static int privateFive = 5;

    public void deleteSilentOrbitAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SILENT_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SilentOrbitSafeSink()).applySilentOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SilentOrbitSafeSink {
    public void applySilentOrbitDeletion(String data, boolean authorized) throws SQLException {
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        try {
            PreparedStatement silentOrbitDelete = silentOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentOrbitDelete.setString(1, data);
            if (authorized) {
                silentOrbitDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentOrbitConnection.close();
        }
    }
}
