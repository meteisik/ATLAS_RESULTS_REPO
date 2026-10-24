import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentOrbit {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_ORBIT_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentOrbitSink()).applySilentOrbitDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentOrbitSink {
    public void applySilentOrbitDeletion(CWE284_P09_V1_SilentOrbit.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        try {
            PreparedStatement silentOrbitDelete = silentOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentOrbitDelete.setString(1, data);
            silentOrbitDelete.executeUpdate();
        } finally {
            silentOrbitConnection.close();
        }
    }
}
