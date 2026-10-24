import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SolarCipher {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSolarCipherAccount() throws SQLException {
        String data;
        data = System.getenv("SOLAR_CIPHER_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SolarCipherSink()).applySolarCipherDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SolarCipherSink {
    public void applySolarCipherDeletion(CWE284_P09_V1_SolarCipher.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection solarCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarCipher");
        try {
            PreparedStatement solarCipherDelete = solarCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarCipherDelete.setString(1, data);
            solarCipherDelete.executeUpdate();
        } finally {
            solarCipherConnection.close();
        }
    }
}
