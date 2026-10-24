import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_OnyxCometSafe {

    private String onyxCometAccountId;

    private boolean onyxCometAuthorized;

    private void applyOnyxCometDeletion() throws SQLException {
        String data = onyxCometAccountId;
        boolean authorized = onyxCometAuthorized;
        Connection onyxCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxComet");
        try {
            PreparedStatement onyxCometDelete = onyxCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxCometDelete.setString(1, data);
            if (authorized) {
                onyxCometDelete.executeUpdate();
            }
        } finally {
            onyxCometConnection.close();
        }
    }

    public void deleteOnyxCometAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ONYX_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        onyxCometAccountId = data;
        onyxCometAuthorized = isAuthorized(data);
        applyOnyxCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
