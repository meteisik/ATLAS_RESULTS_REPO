import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_IvoryBeaconSafe {
    private static boolean privateTrue = true;

    public void deleteIvoryBeaconAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("IVORY_BEACON_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection ivoryBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryBeacon");
            try {
                PreparedStatement ivoryBeaconDelete = ivoryBeaconConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                ivoryBeaconDelete.setString(1, data);
                if (authorized) {
                    ivoryBeaconDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                ivoryBeaconConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
