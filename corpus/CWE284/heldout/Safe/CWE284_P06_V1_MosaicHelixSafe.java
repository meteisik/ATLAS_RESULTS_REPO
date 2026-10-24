import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicHelixSafe {

    public void deleteMosaicHelixAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HELIX_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicHelixSafeSink()).applyMosaicHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicHelixSafeSink {
    public void applyMosaicHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
        try {
            PreparedStatement mosaicHelixDelete = mosaicHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicHelixDelete.setString(1, data);
            if (authorized) {
                mosaicHelixDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicHelixConnection.close();
        }
    }
}
