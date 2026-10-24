import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentOrbit {

    public static String data;

    public static boolean authorized;

    public void deleteSilentOrbitAccount() throws SQLException {
        data = System.getenv("SILENT_ORBIT_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentOrbitSink()).applySilentOrbitDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentOrbitSink {
    public void applySilentOrbitDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentOrbit.data;
        boolean authorized = CWE284_P10_V1_SilentOrbit.authorized;
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        try {
            PreparedStatement silentOrbitDelete = silentOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentOrbitDelete.setString(1, data);
            silentOrbitDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentOrbitConnection.close();
        }
    }
}
