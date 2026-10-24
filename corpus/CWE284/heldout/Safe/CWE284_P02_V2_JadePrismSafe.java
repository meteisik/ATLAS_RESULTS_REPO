import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_JadePrismSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteJadePrismAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = System.getenv("JADE_PRISM_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection jadePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadePrism");
            try {
                PreparedStatement jadePrismDelete = jadePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                jadePrismDelete.setString(1, data);
                if (authorized) {
                    jadePrismDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                jadePrismConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
