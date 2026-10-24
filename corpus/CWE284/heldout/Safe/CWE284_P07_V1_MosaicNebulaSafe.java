import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_MosaicNebulaSafe {

    public void deleteMosaicNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_NEBULA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_MosaicNebulaSafeChecker()).isAuthorized(data);
        Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
        try {
            PreparedStatement mosaicNebulaDelete = mosaicNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicNebulaDelete.setString(1, data);
            if (authorized) {
                mosaicNebulaDelete.executeUpdate();
            }
        } finally {
            mosaicNebulaConnection.close();
        }
    }
}

class CWE284_P07_V1_MosaicNebulaSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
