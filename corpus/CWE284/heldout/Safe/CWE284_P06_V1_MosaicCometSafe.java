import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicCometSafe {

    public void deleteMosaicCometAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_COMET_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicCometSafeSink()).applyMosaicCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicCometSafeSink {
    public void applyMosaicCometDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicComet");
        try {
            PreparedStatement mosaicCometDelete = mosaicCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicCometDelete.setString(1, data);
            if (authorized) {
                mosaicCometDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicCometConnection.close();
        }
    }
}
