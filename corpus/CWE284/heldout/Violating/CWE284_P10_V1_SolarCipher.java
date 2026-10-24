import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SolarCipher {

    public static String data;

    public static boolean authorized;

    public void deleteSolarCipherAccount() throws SQLException {
        data = System.getenv("SOLAR_CIPHER_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SolarCipherSink()).applySolarCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SolarCipherSink {
    public void applySolarCipherDeletion() throws SQLException {
        String data = CWE284_P10_V1_SolarCipher.data;
        boolean authorized = CWE284_P10_V1_SolarCipher.authorized;
        Connection solarCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarCipher");
        try {
            PreparedStatement solarCipherDelete = solarCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            solarCipherDelete.setString(1, data);
            solarCipherDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            solarCipherConnection.close();
        }
    }
}
