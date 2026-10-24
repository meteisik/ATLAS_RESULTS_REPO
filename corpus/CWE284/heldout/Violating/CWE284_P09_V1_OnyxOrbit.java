import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxOrbit {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_ORBIT_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxOrbitSink()).applyOnyxOrbitDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxOrbitSink {
    public void applyOnyxOrbitDeletion(CWE284_P09_V1_OnyxOrbit.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        try {
            PreparedStatement onyxOrbitDelete = onyxOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxOrbitDelete.setString(1, data);
            onyxOrbitDelete.executeUpdate();
        } finally {
            onyxOrbitConnection.close();
        }
    }
}
