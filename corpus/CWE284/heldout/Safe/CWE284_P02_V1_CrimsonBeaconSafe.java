import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CrimsonBeaconSafe {

    public void deleteCrimsonBeaconAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("CRIMSON_BEACON_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection crimsonBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonBeacon");
            try {
                PreparedStatement crimsonBeaconDelete = crimsonBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                crimsonBeaconDelete.setString(1, data);
                if (authorized) {
                    crimsonBeaconDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                crimsonBeaconConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
