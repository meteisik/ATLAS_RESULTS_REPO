import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentRaven {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentRavenAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_RAVEN_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentRavenSink()).applySilentRavenDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentRavenSink {
    public void applySilentRavenDeletion(CWE284_P09_V1_SilentRaven.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        try {
            PreparedStatement silentRavenDelete = silentRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentRavenDelete.setString(1, data);
            silentRavenDelete.executeUpdate();
        } finally {
            silentRavenConnection.close();
        }
    }
}
