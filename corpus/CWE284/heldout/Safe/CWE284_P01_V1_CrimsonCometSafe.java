import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CrimsonCometSafe {

    public void deleteCrimsonCometAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_COMET_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
