import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonCometSafe {

    private void applyCrimsonCometDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonComet");
        try {
            PreparedStatement crimsonCometDelete = crimsonCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonCometDelete.setString(1, data);
            if (authorized) {
                crimsonCometDelete.executeUpdate();
            }
        } finally {
            crimsonCometConnection.close();
        }
    }

    public void deleteCrimsonCometAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_COMET_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyCrimsonCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
