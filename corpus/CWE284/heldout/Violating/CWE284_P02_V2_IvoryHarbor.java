import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_IvoryHarbor {
    private static int privateFive = 5;

    public void deleteIvoryHarborAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("IVORY_HARBOR_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection ivoryHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHarbor");
            try {
                PreparedStatement ivoryHarborDelete = ivoryHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                ivoryHarborDelete.setString(1, data);
                ivoryHarborDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                ivoryHarborConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
