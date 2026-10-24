import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_IvoryCometSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteIvoryCometAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = System.getenv("IVORY_COMET_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
            try {
                PreparedStatement ivoryCometDelete = ivoryCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                ivoryCometDelete.setString(1, data);
                if (authorized) {
                    ivoryCometDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                ivoryCometConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
