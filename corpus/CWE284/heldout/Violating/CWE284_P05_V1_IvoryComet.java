import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryComet {

    private String ivoryCometAccountId;

    private boolean ivoryCometAuthorized;

    private void applyIvoryCometDeletion() throws SQLException {
        String data = ivoryCometAccountId;
        boolean authorized = ivoryCometAuthorized;
        Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
        try {
            PreparedStatement ivoryCometDelete = ivoryCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryCometDelete.setString(1, data);
            ivoryCometDelete.executeUpdate();
        } finally {
            ivoryCometConnection.close();
        }
    }

    public void deleteIvoryCometAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_COMET_ACCOUNT_ID");
        ivoryCometAccountId = data;
        ivoryCometAuthorized = isAuthorized(data);
        applyIvoryCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
