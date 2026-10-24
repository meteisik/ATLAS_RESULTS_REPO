import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryCometSafe {

    private boolean checkIvoryCometAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryCometAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_COMET_ACCOUNT_ID");
        boolean authorized = checkIvoryCometAccess(data);
        Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
        try {
            PreparedStatement ivoryCometDelete = ivoryCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryCometDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryCometDelete.executeUpdate();
            }
        } finally {
            ivoryCometConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
